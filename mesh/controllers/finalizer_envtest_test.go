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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
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
		netv1.AddToScheme, compiledv1.AddToScheme, computev1.AddToScheme, storagev1.AddToScheme,
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
	if err := (&CompiledNICReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		t.Fatalf("setup nic reconciler: %v", err)
	}
	// Both of these root on VirtualMachine — the dual-finalizer case below depends on it.
	if err := (&CompiledVMReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		t.Fatalf("setup vm reconciler: %v", err)
	}
	if err := (&CompiledVolumeAttachmentReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		t.Fatalf("setup attachment reconciler: %v", err)
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

	t.Run("NICTeardown", func(t *testing.T) {
		nic := &netv1.NetworkInterface{}
		nic.Name = "nic-teardown"
		nic.Namespace = "default"
		nic.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
		mustCreate(ctx, t, direct, nic)
		markNICAllocated(ctx, t, direct, client.ObjectKey{Namespace: "default", Name: "nic-teardown"}, "10.0.0.20")

		twin := client.ObjectKey{Namespace: "default", Name: "default-nic-teardown"}
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

		twin := client.ObjectKey{Namespace: "default", Name: "default-nic-regressed"}
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

		vmTwin := client.ObjectKey{Namespace: "default", Name: "default-vm-teardown"}
		attTwin := client.ObjectKey{Namespace: "default", Name: "vm-teardown-vol-a"}
		mustExistEventually(ctx, t, direct, vmTwin, &compiledv1.CompiledVM{})
		mustExistEventually(ctx, t, direct, attTwin, &compiledv1.CompiledVolumeAttachment{})

		mustDelete(ctx, t, direct, vm)
		mustBeGoneEventually(ctx, t, direct, vmTwin, &compiledv1.CompiledVM{})
		mustBeGoneEventually(ctx, t, direct, attTwin, &compiledv1.CompiledVolumeAttachment{})
		mustBeGoneEventually(ctx, t, direct, client.ObjectKeyFromObject(vm), &computev1.VirtualMachine{})
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
