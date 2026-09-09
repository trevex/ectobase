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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

// TestIPAMEndToEndEnvtest wires the real allocate→gate→compile chain (VPC, Subnet, NIC-IPAM and
// CompiledNIC reconcilers) into one manager against a real in-process apiserver and proves the
// full path: a VPC + a spec-only Subnet (driven Ready by the SubnetReconciler) + a NIC with empty
// Spec.IPs eventually yields a CompiledNIC carrying exactly one allocated 10.0.1.x overlay IP.
// Skips cleanly when KUBEBUILDER_ASSETS is unset (outside the nix devShell).
func TestIPAMEndToEndEnvtest(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS unset; run inside `nix develop` for the envtest apiserver assets")
	}
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := compiledv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	// CompiledNICReconciler watches computev1 VirtualMachine/Container for placement.
	if err := computev1.AddToScheme(scheme); err != nil {
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

	// NIC-IPAM and CompiledNIC reconcilers both root on NetworkInterface; the NIC-IPAM controller
	// carries an explicit .Named("nicipam"), so the two no longer collide under the manager's
	// default controller-name uniqueness validation (production-equivalent, no SkipNameValidation).
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Wire the real chain: allocate (VPC → Subnet → NIC-IPAM) then gate+compile (CompiledNIC).
	if err := (&VPCReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader()}).SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}
	if err := (&SubnetReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader()}).SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}
	if err := (&NICIPAMReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader()}).SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}
	if err := (&CompiledNICReconciler{Client: mgr.GetClient(), DefaultClusterName: "pool-a"}).SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = mgr.Start(ctx) }()
	if !mgr.GetCache().WaitForCacheSync(ctx) {
		t.Fatal("cache sync")
	}
	direct, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}

	mustCreate(ctx, t, direct, &netv1.VPC{ObjectMeta: metav1.ObjectMeta{Name: "blue", Namespace: "default"}})
	// Subnet: create with spec only — the real SubnetReconciler drives Status Ready (envtest ignores
	// any in-memory Status set on create, so readySubnet must NOT be used here).
	mustCreate(ctx, t, direct, &netv1.Subnet{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "default"},
		Spec:       netv1.SubnetSpec{VPCRef: netv1.LocalObjectReference{Name: "blue"}, V4Prefix: sp("10.0.1.0/24")},
	})
	mustCreate(ctx, t, direct, &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "nic", Namespace: "default"},
		Spec:       netv1.NetworkInterfaceSpec{VPCRef: netv1.LocalObjectReference{Name: "blue"}, SubnetRef: netv1.LocalObjectReference{Name: "s"}},
	})

	eventually(t, 40*time.Second, func() error {
		var c compiledv1.CompiledNIC
		if err := direct.Get(ctx, client.ObjectKey{Namespace: "default", Name: "default-nic"}, &c); err != nil {
			return err
		}
		if len(c.Spec.OverlayIPs) != 1 {
			return fmt.Errorf("overlay IPs = %v", c.Spec.OverlayIPs)
		}
		return nil
	})
}
