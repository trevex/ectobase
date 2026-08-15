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

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

// TestVPCControllerEnvtest runs the VNI allocator against a REAL in-process apiserver
// (controller-runtime envtest) via SetupWithManager. It proves the allocation algorithm
// end-to-end against a real status subresource: distinct auto-allocated VNIs, reuse of a
// freed VNI, honored pins, pin-collision → Conflict, and idempotency. Skips cleanly when
// KUBEBUILDER_ASSETS is unset (outside the nix devShell).
func TestVPCControllerEnvtest(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS unset; run inside `nix develop` for the envtest apiserver assets")
	}

	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
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
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"}, // disable the metrics listener (port clash)
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if err := (&VPCReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader()}).SetupWithManager(mgr); err != nil {
		t.Fatalf("setup reconciler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgrDone := make(chan error, 1)
	go func() { mgrDone <- mgr.Start(ctx) }()
	if !mgr.GetCache().WaitForCacheSync(ctx) {
		t.Fatal("manager cache did not sync")
	}

	direct, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("direct client: %v", err)
	}

	// --- Allocation: 3 auto-allocated VPCs get distinct VNIs in [1000, …], all Ready. ---
	mustCreate(ctx, t, direct, newVPC("alloc-a", nil))
	mustCreate(ctx, t, direct, newVPC("alloc-b", nil))
	mustCreate(ctx, t, direct, newVPC("alloc-c", nil))

	var vniA, vniB, vniC int32
	eventually(t, 20*time.Second, func() error {
		var err error
		if vniA, err = readyVNI(ctx, direct, "alloc-a"); err != nil {
			return err
		}
		if vniB, err = readyVNI(ctx, direct, "alloc-b"); err != nil {
			return err
		}
		if vniC, err = readyVNI(ctx, direct, "alloc-c"); err != nil {
			return err
		}
		return nil
	})
	for _, v := range []int32{vniA, vniB, vniC} {
		if v < VNIAllocStart || v > VNIAllocEnd {
			t.Fatalf("auto-allocated VNI %d out of range [%d,%d]", v, VNIAllocStart, VNIAllocEnd)
		}
	}
	if vniA == vniB || vniA == vniC || vniB == vniC {
		t.Fatalf("auto-allocated VNIs collide: a=%d b=%d c=%d", vniA, vniB, vniC)
	}

	// --- Reuse on free: delete the lowest-VNI VPC; a new VPC reclaims exactly that VNI. ---
	freed, freedName := vniA, "alloc-a"
	for name, v := range map[string]int32{"alloc-a": vniA, "alloc-b": vniB, "alloc-c": vniC} {
		if v < freed {
			freed, freedName = v, name
		}
	}
	del := &netv1.VPC{}
	del.Name, del.Namespace = freedName, "default"
	if err := direct.Delete(ctx, del); err != nil {
		t.Fatalf("delete %s: %v", freedName, err)
	}
	// Wait for the delete to be observable via a strong read (the allocator reads via APIReader).
	eventually(t, 20*time.Second, func() error {
		var got netv1.VPC
		err := direct.Get(ctx, client.ObjectKey{Namespace: "default", Name: freedName}, &got)
		if err == nil {
			return fmt.Errorf("%s still present", freedName)
		}
		return nil
	})

	mustCreate(ctx, t, direct, newVPC("reuse", nil))
	eventually(t, 20*time.Second, func() error {
		v, err := readyVNI(ctx, direct, "reuse")
		if err != nil {
			return err
		}
		if v != freed {
			return fmt.Errorf("reuse VNI=%d want freed %d", v, freed)
		}
		return nil
	})

	// --- Pin honored: spec.vni=4242 → status.vni==4242, Ready. ---
	mustCreate(ctx, t, direct, newVPC("pinned", ptr(int32(4242))))
	eventually(t, 20*time.Second, func() error {
		v, err := readyVNI(ctx, direct, "pinned")
		if err != nil {
			return err
		}
		if v != 4242 {
			return fmt.Errorf("pinned VNI=%d want 4242", v)
		}
		return nil
	})

	// --- Pin collision: two VPCs both pinning 5000 → exactly one Ready(5000), other Conflict. ---
	mustCreate(ctx, t, direct, newVPC("pin-x", ptr(int32(5000))))
	mustCreate(ctx, t, direct, newVPC("pin-y", ptr(int32(5000))))
	eventually(t, 25*time.Second, func() error {
		x, err := getVPC(ctx, direct, "pin-x")
		if err != nil {
			return err
		}
		y, err := getVPC(ctx, direct, "pin-y")
		if err != nil {
			return err
		}
		// Both must have a settled state.
		if x.Status.State == "" || y.Status.State == "" {
			return fmt.Errorf("state not yet settled: x=%q y=%q", x.Status.State, y.Status.State)
		}
		readies := 0
		conflicts := 0
		for _, v := range []*netv1.VPC{x, y} {
			switch v.Status.State {
			case vpcStateReady:
				if v.Status.VNI != 5000 {
					return fmt.Errorf("%s Ready but VNI=%d want 5000", v.Name, v.Status.VNI)
				}
				readies++
			case vpcStateConflict:
				if v.Status.VNI == 5000 {
					return fmt.Errorf("%s Conflict but grabbed VNI 5000", v.Name)
				}
				conflicts++
			default:
				return fmt.Errorf("%s unexpected state %q", v.Name, v.Status.State)
			}
		}
		if readies != 1 || conflicts != 1 {
			return fmt.Errorf("want exactly 1 Ready + 1 Conflict, got ready=%d conflict=%d", readies, conflicts)
		}
		return nil
	})

	// --- Idempotent: a settled Ready VPC's status doesn't change across further reconciles. ---
	before, err := getVPC(ctx, direct, "pinned")
	if err != nil {
		t.Fatalf("get pinned: %v", err)
	}
	// Nudge the object to trigger a reconcile (label change, spec untouched).
	before.Labels = map[string]string{"nudge": "1"}
	if err := direct.Update(ctx, before); err != nil {
		t.Fatalf("update pinned: %v", err)
	}
	// Give the reconcile a moment, then assert VNI+state are unchanged and stable.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got, err := getVPC(ctx, direct, "pinned")
		if err != nil {
			t.Fatalf("get pinned: %v", err)
		}
		if got.Status.VNI != 4242 || got.Status.State != vpcStateReady {
			t.Fatalf("idempotency broken: VNI=%d state=%q", got.Status.VNI, got.Status.State)
		}
		time.Sleep(200 * time.Millisecond)
	}

	cancel()
	select {
	case <-mgrDone:
	case <-time.After(10 * time.Second):
		t.Fatal("manager did not shut down")
	}
}

// newVPC builds a VPC in the default namespace with an optional pinned VNI.
func newVPC(name string, vni *int32) *netv1.VPC {
	v := &netv1.VPC{}
	v.Name = name
	v.Namespace = "default"
	v.Spec.VNI = vni
	return v
}

func getVPC(ctx context.Context, c client.Client, name string) (*netv1.VPC, error) {
	var v netv1.VPC
	if err := c.Get(ctx, client.ObjectKey{Namespace: "default", Name: name}, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// readyVNI returns the VPC's status.vni once it is Ready, else an error to keep polling.
func readyVNI(ctx context.Context, c client.Client, name string) (int32, error) {
	v, err := getVPC(ctx, c, name)
	if err != nil {
		return 0, err
	}
	if v.Status.State != vpcStateReady {
		return 0, fmt.Errorf("%s state=%q want Ready", name, v.Status.State)
	}
	return v.Status.VNI, nil
}
