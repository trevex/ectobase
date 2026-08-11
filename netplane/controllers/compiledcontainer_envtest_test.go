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
	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

// TestCompiledContainerControllerEnvtest proves — against a real in-process apiserver — that a
// Container is the placement AUTHORITY for its owned NICs and emits a CompiledContainer:
//
//   - Given a Container{clusterName:c1, nodeName:n1, interfaceRefs:[nic-a]} + a NetworkInterface nic-a
//     with NO clusterName/nodeName of its own + a Ready VPC, the produced CompiledNIC (default-nic-a)
//     inherits spec.clusterName==c1 AND spec.nodeName==n1 from the Container.
//   - A CompiledContainer (default-ctr1) is emitted with spec.clusterName==c1, spec.nodeName==n1, and
//     one Interfaces[] entry for nic-a (MAC + NetworkInterfaceRef).
//
// Skips cleanly when KUBEBUILDER_ASSETS is unset (i.e. outside the nix devShell).
func TestCompiledContainerControllerEnvtest(t *testing.T) {
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

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
		// Shares the test binary (global controller-name registry) with the other envtest managers,
		// which derive the same "networkinterface"/"container" controller names.
		Controller: config.Controller{SkipNameValidation: ptrTo(true)},
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if err := (&CompiledNICReconciler{Client: mgr.GetClient(), DefaultClusterName: "default-cluster"}).SetupWithManager(mgr); err != nil {
		t.Fatalf("setup compilednic reconciler: %v", err)
	}
	if err := (&CompiledContainerReconciler{Client: mgr.GetClient(), NetworkName: "flowplane-overlay"}).SetupWithManager(mgr); err != nil {
		t.Fatalf("setup compiledcontainer reconciler: %v", err)
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

	// A Ready VPC so the NIC's VNI resolves (status.vni is a subresource → set separately).
	vpc := &netv1.VPC{}
	vpc.Name = "blue"
	vpc.Namespace = "default"
	mustCreate(ctx, t, direct, vpc)
	vpc.Status.VNI = 100
	if err := direct.Status().Update(ctx, vpc); err != nil {
		t.Fatalf("set vpc vni: %v", err)
	}

	// A NIC with NO clusterName/nodeName of its own — placement must come from the owning Container.
	nic := &netv1.NetworkInterface{}
	nic.Name = "nic-a"
	nic.Namespace = "default"
	nic.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
	nic.Spec.IPs = []string{"10.0.0.10"}
	nic.Spec.MAC = "02:00:00:00:00:aa"
	mustCreate(ctx, t, direct, nic)

	// The owning Container: placement authority (clusterName + nodeName).
	ctr := &computev1.Container{}
	ctr.Name = "ctr1"
	ctr.Namespace = "default"
	ctr.Spec.ClusterName = "c1"
	ctr.Spec.NodeName = "n1"
	ctr.Spec.Image = "nginx:latest"
	ctr.Spec.InterfaceRefs = []computev1.LocalObjectReference{{Name: "nic-a"}}
	mustCreate(ctx, t, direct, ctr)

	// The CompiledNIC inherits clusterName from the Container (nodeName is no longer stamped
	// on CompiledNIC — the agent self-locates via the dataplane's ListInterfaces instead).
	eventually(t, 15*time.Second, func() error {
		var c compiledv1.CompiledNIC
		if err := direct.Get(ctx, client.ObjectKey{Namespace: "default", Name: "default-nic-a"}, &c); err != nil {
			return err
		}
		if c.Spec.ClusterName != "c1" {
			return fmt.Errorf("clusterName=%q want c1", c.Spec.ClusterName)
		}
		return nil
	})

	// The CompiledContainer is emitted with placement + one resolved interface.
	eventually(t, 15*time.Second, func() error {
		var cc compiledv1.CompiledContainer
		if err := direct.Get(ctx, client.ObjectKey{Namespace: "default", Name: "default-ctr1"}, &cc); err != nil {
			return err
		}
		if cc.Spec.ClusterName != "c1" {
			return fmt.Errorf("clusterName=%q want c1", cc.Spec.ClusterName)
		}
		if cc.Spec.NodeName != "n1" {
			return fmt.Errorf("nodeName=%q want n1", cc.Spec.NodeName)
		}
		if cc.Spec.Image != "nginx:latest" {
			return fmt.Errorf("image=%q want nginx:latest", cc.Spec.Image)
		}
		if len(cc.Spec.Interfaces) != 1 {
			return fmt.Errorf("interfaces=%d want 1: %+v", len(cc.Spec.Interfaces), cc.Spec.Interfaces)
		}
		iface := cc.Spec.Interfaces[0]
		if iface.NetworkName != "flowplane-overlay" {
			return fmt.Errorf("iface.NetworkName=%q want flowplane-overlay", iface.NetworkName)
		}
		if iface.MAC != "02:00:00:00:00:aa" {
			return fmt.Errorf("iface.MAC=%q want 02:00:00:00:00:aa", iface.MAC)
		}
		if iface.NetworkInterfaceRef != "default/nic-a" {
			return fmt.Errorf("iface.NetworkInterfaceRef=%q want default/nic-a", iface.NetworkInterfaceRef)
		}
		return nil
	})

	cancel()
	select {
	case <-mgrDone:
	case <-time.After(10 * time.Second):
		t.Fatal("manager did not shut down")
	}
}
