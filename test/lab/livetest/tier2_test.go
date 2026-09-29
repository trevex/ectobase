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

// fenceName mirrors dispatch/pkg/fence/storage.go fenceName(): "ectobase-" +
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

// TestTier2Failover is the Tier-2 fenced cross-cluster VM-reschedule gate. It boots a stateful
// RBD-backed VirtualMachine on pool k02, stops k02's broker heartbeat so the pool goes Unknown, and
// asserts dispatch FENCES k02 (Ceph NetworkFence result==Succeeded + OSD blocklist) then RE-BINDS the
// VM to k03, where the VMI restarts. Recovery restores the heartbeat and asserts the fence releases.
// Best-effort on VMI Running (guest boot under software emulation is slow); the fence + reschedule
// core is the gate.
//
// It now also asserts THE DISK, which it could not before Phase 0 of
// docs/superpowers/specs/2026-09-23-vm-mobility-across-clusters.md: k03 binds the SAME RBD image, by
// CSI handle, and that image is still intact at the end of the failover.
//
// And it asserts the source lets go: once k02's broker is back, it prunes every twin the dispatch
// deleted while it was down, which releases k02's claim on the image k03 now runs — without taking
// the image with it.
//
// testdata/tier2-vm.yaml asserted the reattachment in prose from the day it was written, years before
// anything implemented it, and got away with it because this test created a Volume and then checked
// nothing about it. Hence the handle comparisons below rather than another claim.
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
	applyDispatch(t, ctx, cfg, readFixture(t, "tier2-vm.yaml"))
	patchVNIReady(t, ctx, cfg, "vpcs.net.ectobase.dev", "blue")

	// Best-effort teardown of the fixture regardless of outcome (delete by name; the
	// kubectl helper has no stdin, so `delete -f -` is not usable here).
	t.Cleanup(func() {
		_, _ = kubectl(ctx, cfg, "dispatch", "delete", "virtualmachines.compute.ectobase.dev",
			tier2VMName, "-n", tier2VMNS, "--ignore-not-found", "--wait=false")
		_, _ = kubectl(ctx, cfg, "dispatch", "delete", "volumes.storage.ectobase.dev",
			tier2Volume, "-n", tier2VMNS, "--ignore-not-found", "--wait=false")
		_, _ = kubectl(ctx, cfg, "dispatch", "delete", "networkinterfaces.net.ectobase.dev",
			"tier2-nic", "-n", tier2VMNS, "--ignore-not-found", "--wait=false")
		_, _ = kubectl(ctx, cfg, "dispatch", "delete", "vpcs.net.ectobase.dev",
			"blue", "-n", tier2VMNS, "--ignore-not-found", "--wait=false")
	})

	// --- Phase 3: VM bound to k02 ---------------------------------------------------
	eventually(t, 3*time.Minute, 5*time.Second, func() error {
		return expectVMCluster(ctx, cfg, "k02")
	})

	// --- Phase 4: VMI + the VM's OWN disk Bound on k02 ------------------------------
	//
	// Ten minutes, not five: this fixture has a bootImage, so its claim binds only once CDI has
	// finished importing fedora:41 over the fabric's NAT64. The old five was enough because the old
	// assertion accepted any Bound ceph-rbd PVC — including CDI's prime, which binds first.
	att := attName(tier2VMNS, tier2VMName, tier2Volume)
	eventually(t, 10*time.Minute, 10*time.Second, func() error {
		return expectVMIAndRBD(ctx, cfg, "k02", att)
	})
	if phase, err := kubectl(ctx, cfg, "k02", "-n", tier2VMNS,
		"get", "vmi", tier2VMIName, "-o", "jsonpath={.status.phase}"); err == nil {
		t.Logf("k02 VMI %s phase=%q (not hard-required Running)", tier2VMIName, strings.TrimSpace(phase))
	}

	// --- Phase 5: the disk exists and is PROTECTED -----------------------------------
	//
	// Identify the disk from Ceph's side and wait until its identity has been recorded on the Volume,
	// which is what makes the rest of this test meaningful: only a recorded identity can be stamped
	// into the k03 twin, so only then can k03 adopt the image instead of provisioning a blank one.
	// Before that point a rebind still costs the VM its disk (TestVolumeSurvivesAnImmediateRebind
	// covers exactly that window), and asserting adoption here without waiting would be asserting
	// something this design does not claim.
	pool, err := rbdPool(ctx, cfg, "k02")
	require.NoError(t, err)

	var srcHandle, srcImage string
	eventually(t, 2*time.Minute, 5*time.Second, func() error {
		_, h, img, err := diskPV(ctx, cfg, "k02", att)
		if err != nil {
			return err
		}
		srcHandle, srcImage = h, img
		return nil
	})
	eventually(t, 5*time.Minute, 5*time.Second, func() error {
		out, err := kubectl(ctx, cfg, "dispatch", "get", "volume.storage.ectobase.dev", tier2Volume,
			"-n", tier2VMNS, "-o", "jsonpath={.status.diskIdentity.csi.volumeHandle}")
		if err != nil {
			return fmt.Errorf("read the Volume's recorded identity: %w", err)
		}
		if got := strings.TrimSpace(out); got != srcHandle {
			return fmt.Errorf("Volume records identity %q, want the provisioned disk %q", got, srcHandle)
		}
		return nil
	})
	imgs, err := rbdImages(ctx, cfg, pool)
	require.NoError(t, err)
	require.Contains(t, imgs, srcImage,
		"precondition: the image %s that k02's PV names is not in pool %s, so no verdict about the "+
			"disk can be read from this run", srcImage, pool)
	t.Logf("protected disk on k02: image=%s handle=%s pool=%s", srcImage, srcHandle, pool)

	// --- Phase 6: k02 fence coordinate ----------------------------------------------
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

	// --- Phase 7: drain k02 (stop its broker heartbeat) -----------------------------
	// Instead of `docker kill`ing the node (which destroys its clab fabric veths so the
	// node can never rejoin — flowplane crash-loops and the rest of the live suite
	// fails), stop the broker so k02's ClusterPool lease goes stale → central marks the
	// pool Unknown → the failover reconciler fences + reschedules its VMs. The node +
	// its fabric stay fully intact; recovery is just restarting the broker. This is a
	// split-brain "pool unreachable but node alive" scenario — exactly what storage
	// fencing guards against.
	// Register recovery FIRST so a mid-test failure still restores the heartbeat.
	t.Cleanup(func() {
		_ = scaleBrokerReplicas(context.Background(), cfg, "k02", 1)
	})
	require.NoError(t, scaleBrokerReplicas(ctx, cfg, "k02", 0), "scale down k02 broker (drain)")
	t.Logf("drained k02: scaled its broker to 0 (heartbeat stops → pool goes Unknown)")

	// --- Phase 8: fence asserted (dispatch) ------------------------------------------
	eventually(t, 6*time.Minute, 10*time.Second, func() error {
		res, err := kubectl(ctx, cfg, "dispatch",
			"get", "networkfence", fenceCR, "-o", "jsonpath={.status.result}")
		if err != nil {
			return fmt.Errorf("get NetworkFence %s: %w", fenceCR, err)
		}
		if strings.TrimSpace(res) != "Succeeded" {
			return fmt.Errorf("NetworkFence %s result=%q, want Succeeded", fenceCR, strings.TrimSpace(res))
		}
		return nil
	})

	// --- Phase 9: ceph blocklist contains a k02 client ------------------------------
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

	// --- Phase 10: VM rebinds to k03 -------------------------------------------------
	eventually(t, 6*time.Minute, 10*time.Second, func() error {
		return expectVMCluster(ctx, cfg, "k03")
	})

	// --- Phase 11: VMI + the ORIGINAL disk on k03 -----------------------------------
	eventually(t, 6*time.Minute, 10*time.Second, func() error {
		return expectVMIAndRBD(ctx, cfg, "k03", att)
	})
	// The same image, not merely an image. A blank disk of the right size binds just as well and is
	// indistinguishable in `kubectl get pvc`; only the CSI handle says whether the guest got its data
	// back. This is the assertion the fixture's header used to make in prose.
	eventually(t, 3*time.Minute, 5*time.Second, func() error {
		pv, h, img, err := diskPV(ctx, cfg, "k03", att)
		if err != nil {
			return err
		}
		if h != srcHandle {
			return fmt.Errorf("k03 bound PV %s with image %s (handle %s), want the original %s (handle %s)",
				pv, img, h, srcImage, srcHandle)
		}
		return nil
	})
	t.Logf("k03 adopted the ORIGINAL disk %s across the fence", srcImage)
	if phase, err := kubectl(ctx, cfg, "k03", "-n", tier2VMNS,
		"get", "vmi", tier2VMIName, "-o", "jsonpath={.status.phase}"); err == nil {
		t.Logf("k03 VMI %s phase=%q (not hard-required Running)", tier2VMIName, strings.TrimSpace(phase))
	}

	// --- Phase 12: recovery — restore the broker heartbeat, assert fence released ----
	//
	// If this phase times out with "blocklist still contains k02 client", suspect a STALE entry from
	// an earlier run that was interrupted while the pool was fenced, rather than this run's fence.
	// Ceph drops a blocklist entry only on the Fenced -> Unfenced transition, so a run killed inside
	// the fenced window leaves one behind with a multi-year expiry, and the release of every later
	// fence for that same /64 then looks unfinished. Check `ceph osd blocklist ls` on the ceph node;
	// clearing it means patching the NetworkFence to Unfenced (not deleting it) and letting csi-addons
	// run the removal.
	require.NoError(t, scaleBrokerReplicas(ctx, cfg, "k02", 1), "scale up k02 broker (recover)")
	t.Logf("recovered k02: scaled its broker back to 1 (lease renews → pool Ready → fence released)")

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
		if _, err := kubectl(ctx, cfg, "dispatch", "get", "networkfence", fenceCR); err == nil {
			return fmt.Errorf("NetworkFence %s still present (want deleted)", fenceCR)
		}
		return nil
	})

	// --- Phase 13: the source lets go of the disk, and the disk survives it ---------
	//
	// The one ordering no other test covers: the source detaches MINUTES after the target adopted the
	// same image. k02's broker was down when the dispatch deleted k02's twins, so it never saw a
	// delete event; only the pass it runs on coming back up can find them. Until that pass, k02 holds
	// a VM and a claim on the RWO image k03 is running — with the fence already released in Phase 12.
	//
	// Every source-side object is waited out by name. The claim is the one that matters: it goes with
	// the VolumeAttachment twin, and the Retain PV behind it must leave the image in place.
	sourceLeftovers := []struct{ kind, name string }{
		{"compiledvms.compiled.ectobase.dev", tier2VMIName},
		{"compiledvolumeattachments.compiled.ectobase.dev", att},
		{"compilednics.compiled.ectobase.dev", tier2VMNS + "-tier2-nic"},
		{"virtualmachines.kubevirt.io", tier2VMIName},
		{"persistentvolumeclaims", att},
	}
	eventually(t, 5*time.Minute, 10*time.Second, func() error {
		var left []string
		for _, o := range sourceLeftovers {
			out, err := kubectl(ctx, cfg, "k02", "-n", tier2VMNS,
				"get", o.kind, o.name, "--ignore-not-found", "-o", "name")
			if err != nil {
				return fmt.Errorf("get %s/%s on k02: %w", o.kind, o.name, err)
			}
			if strings.TrimSpace(out) != "" {
				left = append(left, o.kind+"/"+o.name)
			}
		}
		if len(left) > 0 {
			return fmt.Errorf("k02 still holds what failed over to k03: %v", left)
		}
		return nil
	})
	t.Logf("k02 released the VM and its claim after recovery")

	imgs, err = rbdImages(ctx, cfg, pool)
	require.NoError(t, err)
	require.Contains(t, imgs, srcImage,
		"DATA LOSS: image %s is gone from pool %s once the source released its claim", srcImage, pool)
	_, h, _, err := diskPV(ctx, cfg, "k03", att)
	require.NoError(t, err, "k03 lost its claim on the disk when k02 released its own")
	require.Equal(t, srcHandle, h, "k03's disk is no longer the original after k02 released its own")
	t.Logf("failover disk PASS: %s intact and still bound on k03 after k02 released it", srcImage)
}

// scaleBrokerReplicas scales a compute cluster's dispatch-broker deployment. Scaling
// to 0 stops the broker's ClusterPool-lease heartbeat, so the dispatch marks the pool
// Unknown (lease stale) and the Tier-2 failover reconciler fences + reschedules its
// VMs — a non-destructive drain that (unlike killing the node container) preserves the
// node's clab fabric veths, so the node stays usable for the rest of the suite. Scaling
// back to 1 renews the lease → pool Ready → the fence is released.
func scaleBrokerReplicas(ctx context.Context, cfg *config.Config, cluster string, replicas int) error {
	_, err := kubectl(ctx, cfg, cluster, "-n", "ectobase-system",
		"scale", "deploy/dispatch-broker", fmt.Sprintf("--replicas=%d", replicas))
	return err
}

// expectVMCluster asserts the VirtualMachine spec.clusterName equals want.
func expectVMCluster(ctx context.Context, cfg *config.Config, want string) error {
	cn, err := kubectl(ctx, cfg, "dispatch",
		"get", "virtualmachines.compute.ectobase.dev", tier2VMName, "-o", "jsonpath={.spec.clusterName}")
	if err != nil {
		return fmt.Errorf("get VirtualMachine %s clusterName: %w", tier2VMName, err)
	}
	if strings.TrimSpace(cn) != want {
		return fmt.Errorf("VirtualMachine %s clusterName=%q, want %q", tier2VMName, strings.TrimSpace(cn), want)
	}
	return nil
}

// expectVMIAndRBD asserts the KubeVirt VMI exists on the given cluster AND that the VM's own disk
// claim — the PVC named after the attachment — is Bound there on the ceph-rbd StorageClass. It does
// NOT require the VMI phase to be Running.
//
// It used to accept ANY Bound ceph-rbd PVC in the namespace, which two things other than the disk under
// test could satisfy: CDI populates a block import through a "prime" PVC that binds first while the
// named claim stays Pending, and the volume-move tests bind claims of their own in this same namespace
// on these same clusters. Naming the claim makes Bound mean "this VM's disk is attached here" — and on
// the source it additionally means the import has finished, which is when the disk becomes protected.
func expectVMIAndRBD(ctx context.Context, cfg *config.Config, cluster, att string) error {
	if _, err := kubectl(ctx, cfg, cluster, "-n", tier2VMNS, "get", "vmi", tier2VMIName); err != nil {
		return fmt.Errorf("VMI %s not present on %s/%s: %w", tier2VMIName, cluster, tier2VMNS, err)
	}
	out, err := kubectl(ctx, cfg, cluster, "-n", tier2VMNS, "get", "pvc", att,
		"-o", "jsonpath={.spec.storageClassName}|{.status.phase}")
	if err != nil {
		return fmt.Errorf("get PVC %s on %s/%s: %w", att, cluster, tier2VMNS, err)
	}
	f := strings.SplitN(strings.TrimSpace(out), "|", 2)
	if len(f) != 2 || f[0] != "ceph-rbd" || f[1] != "Bound" {
		return fmt.Errorf("PVC %s on %s/%s is %q, want a Bound ceph-rbd claim", att, cluster, tier2VMNS, out)
	}
	return nil
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
