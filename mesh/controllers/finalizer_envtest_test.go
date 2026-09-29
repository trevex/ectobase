// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	storagev1 "github.com/trevex/ectobase/api/storage/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

// TestCompiledTeardownFinalizerEnvtest proves compiled twins are torn down by the source's
// finalizer, not by ownerReferences.
//
// envtest runs kube-apiserver + etcd but NO kube-controller-manager, so owner-ref garbage
// collection never runs here. That is exactly what makes this a proof: if a twin disappears after
// its source is deleted, the finalizer did it. (Before this change these same deletes would leave
// the twin orphaned forever.)
func TestCompiledTeardownFinalizerEnvtest(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS unset; run inside `nix develop` for the envtest apiserver assets")
	}

	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		netv1.AddToScheme, compiledv1.AddToScheme, computev1.AddToScheme, storagev1.AddToScheme, corev1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}

	env := &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "charts", "ectobase-pool", "crd-bases"),
			filepath.Join("..", "..", "test", "crds"),
		},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	defer func() { _ = env.Stop() }()

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:     scheme,
		Metrics:    metricsserver.Options{BindAddress: "0"},
		Controller: config.Controller{SkipNameValidation: ptrTo(true)},
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if err := (&CompiledNICReconciler{Client: mgr.GetClient(), DefaultClusterName: "c1"}).SetupWithManager(mgr); err != nil {
		t.Fatalf("setup nic reconciler: %v", err)
	}
	// Both of these root on VirtualMachine — the dual-finalizer case below depends on it.
	if err := (&CompiledVMReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		t.Fatalf("setup vm reconciler: %v", err)
	}
	if err := (&CompiledVolumeAttachmentReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		t.Fatalf("setup attachment reconciler: %v", err)
	}
	if err := (&CompiledVMReleaseReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		t.Fatalf("setup release reconciler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = mgr.Start(ctx) }()
	if !mgr.GetCache().WaitForCacheSync(ctx) {
		t.Fatal("manager cache did not sync")
	}
	direct, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("direct client: %v", err)
	}
	// All three subtests place into cluster "c1" (via DefaultClusterName or vm.Spec.ClusterName),
	// so the twins all land in this one per-pool namespace. The apiserver enforces
	// NamespaceLifecycle, so it must exist before any compiler can create a twin in it.
	mustCreate(ctx, t, direct, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "pool-c1"}})
	mustCreate(ctx, t, direct, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "pool-c2"}})

	t.Run("NICTeardown", func(t *testing.T) {
		nic := &netv1.NetworkInterface{}
		nic.Name = "nic-teardown"
		nic.Namespace = "default"
		nic.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
		mustCreate(ctx, t, direct, nic)
		markNICAllocated(ctx, t, direct, client.ObjectKey{Namespace: "default", Name: "nic-teardown"}, "10.0.0.20")

		twin := client.ObjectKey{Namespace: "pool-c1", Name: "default-nic-teardown"}
		mustExistEventually(ctx, t, direct, twin, &compiledv1.CompiledNIC{})

		mustDelete(ctx, t, direct, nic)
		// Twin gone AND the source actually completed deletion (i.e. the finalizer was released,
		// not left behind pinning the NIC in Terminating).
		mustBeGoneEventually(ctx, t, direct, twin, &compiledv1.CompiledNIC{})
		mustBeGoneEventually(ctx, t, direct, client.ObjectKeyFromObject(nic), &netv1.NetworkInterface{})
	})

	t.Run("KeepLastGoodStillTearsDown", func(t *testing.T) {
		// A NIC that compiled a twin and then regressed out of Allocated keeps its twin
		// (keep-last-good) and short-circuits the IPAM gate. Teardown must still run — this is
		// why the deletion branch sits BEFORE that gate. With the gate first, the reconcile
		// would return early and the NIC would hang in Terminating with an orphaned twin.
		nic := &netv1.NetworkInterface{}
		nic.Name = "nic-regressed"
		nic.Namespace = "default"
		nic.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
		mustCreate(ctx, t, direct, nic)
		key := client.ObjectKey{Namespace: "default", Name: "nic-regressed"}
		markNICAllocated(ctx, t, direct, key, "10.0.0.21")

		twin := client.ObjectKey{Namespace: "pool-c1", Name: "default-nic-regressed"}
		mustExistEventually(ctx, t, direct, twin, &compiledv1.CompiledNIC{})

		// Regress out of Allocated; the twin is deliberately left in place.
		var cur netv1.NetworkInterface
		if err := direct.Get(ctx, key, &cur); err != nil {
			t.Fatal(err)
		}
		cur.Status.State = "Invalid"
		if err := direct.Status().Update(ctx, &cur); err != nil {
			t.Fatal(err)
		}

		mustDelete(ctx, t, direct, &cur)
		mustBeGoneEventually(ctx, t, direct, twin, &compiledv1.CompiledNIC{})
		mustBeGoneEventually(ctx, t, direct, key, &netv1.NetworkInterface{})
	})

	t.Run("VMTeardownBothTwins", func(t *testing.T) {
		// One source, two compilers, two finalizers. Both must release or the VM never deletes.
		vol := &storagev1.Volume{}
		vol.Name = "vol-a"
		vol.Namespace = "default"
		vol.Spec.Size = resource.MustParse("1Gi")
		mustCreate(ctx, t, direct, vol)

		vm := &computev1.VirtualMachine{}
		vm.Name = "vm-teardown"
		vm.Namespace = "default"
		vm.Spec.ClusterName = "c1"
		vm.Spec.VolumeRefs = []computev1.LocalObjectReference{{Name: "vol-a"}}
		mustCreate(ctx, t, direct, vm)

		// The attachment twin name is namespace-qualified: "<vm.Namespace>-<vm.Name>-<ref.Name>".
		vmTwin := client.ObjectKey{Namespace: "pool-c1", Name: "default-vm-teardown"}
		attTwin := client.ObjectKey{Namespace: "pool-c1", Name: "default-vm-teardown-vol-a"}
		mustExistEventually(ctx, t, direct, vmTwin, &compiledv1.CompiledVM{})
		mustExistEventually(ctx, t, direct, attTwin, &compiledv1.CompiledVolumeAttachment{})

		mustDelete(ctx, t, direct, vm)
		// Deleting a VM retires its twin like any move does; it goes once its pool reports release.
		releaseAsBroker(ctx, t, direct, vmTwin)
		mustBeGoneEventually(ctx, t, direct, vmTwin, &compiledv1.CompiledVM{})
		mustBeGoneEventually(ctx, t, direct, attTwin, &compiledv1.CompiledVolumeAttachment{})
		mustBeGoneEventually(ctx, t, direct, client.ObjectKeyFromObject(vm), &computev1.VirtualMachine{})
	})

	t.Run("MoveWaitsForSourceRelease", func(t *testing.T) {
		vol := &storagev1.Volume{}
		vol.Name = "vol-move"
		vol.Namespace = "default"
		vol.Spec.Size = resource.MustParse("1Gi")
		mustCreate(ctx, t, direct, vol)

		vm := &computev1.VirtualMachine{}
		vm.Name = "vm-move"
		vm.Namespace = "default"
		vm.Spec.ClusterName = "c1"
		vm.Spec.VolumeRefs = []computev1.LocalObjectReference{{Name: "vol-move"}}
		mustCreate(ctx, t, direct, vm)

		srcVM := client.ObjectKey{Namespace: "pool-c1", Name: "default-vm-move"}
		srcAtt := client.ObjectKey{Namespace: "pool-c1", Name: "default-vm-move-vol-move"}
		dstVM := client.ObjectKey{Namespace: "pool-c2", Name: "default-vm-move"}
		dstAtt := client.ObjectKey{Namespace: "pool-c2", Name: "default-vm-move-vol-move"}
		mustExistEventually(ctx, t, direct, srcVM, &compiledv1.CompiledVM{})
		mustExistEventually(ctx, t, direct, srcAtt, &compiledv1.CompiledVolumeAttachment{})

		var cur computev1.VirtualMachine
		if err := direct.Get(ctx, client.ObjectKeyFromObject(vm), &cur); err != nil {
			t.Fatal(err)
		}
		cur.Spec.ClusterName = "c2"
		if err := direct.Update(ctx, &cur); err != nil {
			t.Fatal(err)
		}

		// The source's attachment goes at once; the source VM twin is retired and held.
		mustBeGoneEventually(ctx, t, direct, srcAtt, &compiledv1.CompiledVolumeAttachment{})
		// Nothing lands in the target while the source has not released — hold for a few seconds
		// of reconcile churn to make "never" meaningful.
		for i := 0; i < 15; i++ {
			for _, k := range []struct {
				key client.ObjectKey
				obj client.Object
			}{{dstVM, &compiledv1.CompiledVM{}}, {dstAtt, &compiledv1.CompiledVolumeAttachment{}}} {
				if err := direct.Get(ctx, k.key, k.obj); err == nil {
					t.Fatalf("%s compiled into the target before the source released the VM", k.key)
				}
			}
			time.Sleep(200 * time.Millisecond)
		}
		var moving computev1.VirtualMachine
		if err := direct.Get(ctx, client.ObjectKeyFromObject(vm), &moving); err != nil {
			t.Fatal(err)
		}
		if c := meta.FindStatusCondition(moving.Status.Conditions, "Moving"); c == nil ||
			c.Status != metav1.ConditionTrue || c.Reason != "WaitingForSourceRelease" {
			t.Fatalf("want Moving=True/WaitingForSourceRelease while held, got %+v", c)
		}

		releaseAsBroker(ctx, t, direct, srcVM)
		mustBeGoneEventually(ctx, t, direct, srcVM, &compiledv1.CompiledVM{})
		mustExistEventually(ctx, t, direct, dstVM, &compiledv1.CompiledVM{})
		mustExistEventually(ctx, t, direct, dstAtt, &compiledv1.CompiledVolumeAttachment{})

		deadline := time.Now().Add(30 * time.Second)
		for {
			if err := direct.Get(ctx, client.ObjectKeyFromObject(vm), &moving); err != nil {
				t.Fatal(err)
			}
			if c := meta.FindStatusCondition(moving.Status.Conditions, "Moving"); c != nil &&
				c.Status == metav1.ConditionFalse && c.Reason == "Moved" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("Moving never closed: %+v", moving.Status.Conditions)
			}
			time.Sleep(200 * time.Millisecond)
		}
	})
}

// mustExistEventually polls until key resolves, so tests don't race the reconciler.
func mustExistEventually(ctx context.Context, t *testing.T, c client.Client, key client.ObjectKey, into client.Object) {
	t.Helper()
	eventually(t, 20*time.Second, func() error {
		if err := c.Get(ctx, key, into); err != nil {
			return fmt.Errorf("get %s: %w", key, err)
		}
		return nil
	})
}

// mustBeGoneEventually polls until key no longer resolves.
func mustBeGoneEventually(ctx context.Context, t *testing.T, c client.Client, key client.ObjectKey, into client.Object) {
	t.Helper()
	eventually(t, 20*time.Second, func() error {
		err := c.Get(ctx, key, into)
		if err == nil {
			return fmt.Errorf("%s still exists", key)
		}
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("get %s: %w", key, err)
		}
		return nil
	})
}

func mustDelete(ctx context.Context, t *testing.T, c client.Client, obj client.Object) {
	t.Helper()
	if err := c.Delete(ctx, obj); err != nil {
		t.Fatalf("delete %s: %v", client.ObjectKeyFromObject(obj), err)
	}
}

// releaseAsBroker plays the source pool's broker: it waits for the twin to be retired
// (Terminating), then reports the pool has let go of it.
func releaseAsBroker(ctx context.Context, t *testing.T, c client.Client, key client.ObjectKey) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		var twin compiledv1.CompiledVM
		err := c.Get(ctx, key, &twin)
		if err == nil && !twin.DeletionTimestamp.IsZero() {
			orig := twin.DeepCopy()
			twin.Status.Released = true
			if err := c.Status().Patch(ctx, &twin, client.MergeFrom(orig)); err != nil {
				t.Fatalf("report release of %s: %v", key, err)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("twin %s was never retired (last err=%v)", key, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
